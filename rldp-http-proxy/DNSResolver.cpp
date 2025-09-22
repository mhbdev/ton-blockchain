/*
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.
*/
#include "DNSResolver.h"
#include "td/utils/overloaded.h"
#include "common/delay.h"

static const double CACHE_TIMEOUT_HARD = 300.0;
static const double CACHE_TIMEOUT_SOFT = 270.0;

DNSResolver::DNSResolver(td::actor::ActorId<tonlib::TonlibClientWrapper> tonlib_client)
    : tonlib_client_(std::move(tonlib_client)) {
}

void DNSResolver::start_up() {
  sync();
}

void DNSResolver::sync() {
  auto obj = tonlib_api::make_object<tonlib_api::sync>();
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](
                                          td::Result<tonlib_api::object_ptr<tonlib_api::ton_blockIdExt>> R) {
    if (R.is_error()) {
      LOG(WARNING) << "Sync error: " << R.move_as_error();
      ton::delay_action([SelfId]() { td::actor::send_closure(SelfId, &DNSResolver::sync); }, td::Timestamp::in(5.0));
    }
  });
  td::actor::send_closure(tonlib_client_, &tonlib::TonlibClientWrapper::send_request<tonlib_api::sync>, std::move(obj),
                          std::move(P));
}

void DNSResolver::resolve(std::string host, td::Promise<std::string> promise) {
  LOG(INFO) << "[DNS TRACE] Received initial request to resolve: " << host;

  auto it = cache_.find(host);
  if (it != cache_.end()) {
    const CacheEntry &entry = it->second;
    double now = td::Time::now();
    if (now < entry.created_at_ + CACHE_TIMEOUT_HARD) {
      LOG(INFO) << "[DNS TRACE] Found valid cache entry for " << host;
      promise.set_result(entry.address_);
      promise.reset();
      if (now < entry.created_at_ + CACHE_TIMEOUT_SOFT) {
        return;
      }
    }
  }

  resolve_recursive(host, host, nullptr, 0, std::move(promise));
}

void DNSResolver::resolve_recursive(std::string full_host, std::string current_host_part,
                                    tonlib_api::object_ptr<tonlib_api::accountAddress> resolver_address, int depth,
                                    td::Promise<std::string> promise) {
  LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] Resolving '" << current_host_part
            << "' using resolver: " << (resolver_address ? resolver_address->account_address_ : "Root DNS");

  if (depth >= MAX_DNS_HOPS) {
    LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: DNS resolution depth limit exceeded for " << full_host;
    promise.set_error(td::Status::Error("DNS resolution depth limit exceeded"));
    return;
  }

  td::Bits256 category = td::sha256_bits256(td::Slice("site", 4));
  // The TTL of 16 is a reasonable default.
  auto obj = tonlib_api::make_object<tonlib_api::dns_resolve>(std::move(resolver_address), current_host_part, category, 16);

  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise), full_host, depth](
          td::Result<tonlib_api::object_ptr<tonlib_api::dns_resolved>> R) mutable {
        if (R.is_error()) {
          LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: tonlib returned error: " << R.error();
          promise.set_result(R.move_as_error());
          return;
        }
        auto resolved_obj = R.move_as_ok();

        if (resolved_obj->entries_.empty()) {
          LOG(WARNING) << "[DNS TRACE] [Depth " << depth << "] FAILED: No DNS entries found for " << full_host;
          promise.set_error(td::Status::Error("no DNS entries found"));
          return;
        }

        tonlib_api::downcast_call(
            *resolved_obj->entries_[0]->entry_,
            td::overloaded(
                // --- CASE A: RECURSIVE STEP (Next Resolver Found) ---
                [&](tonlib_api::dns_entryDataNextResolver &next) {
                  // The unresolved part of the domain is in the 'name_' field of the returned entry.
                  // We must use this for the next recursive call.
                  std::string remaining_host_part = resolved_obj->entries_[0]->name_;

                  LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] Found next_resolver: " << next.resolver_->account_address_ << ", remaining part: " << remaining_host_part;
                  
                  td::actor::send_closure(SelfId, &DNSResolver::resolve_recursive, std::move(full_host),
                                          std::move(remaining_host_part), std::move(next.resolver_), depth + 1, std::move(promise));
                },
                // --- CASE B: FINAL ANSWER (ADNL Address) ---
                [&](tonlib_api::dns_entryDataAdnlAddress &x) {
                  LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] SUCCESS: Found final ADNL address: " << x.adnl_address_->adnl_address_;
                  auto R = ton::adnl::AdnlNodeIdShort::parse(x.adnl_address_->adnl_address_);
                  if (R.is_ok()) {
                    std::string final_address = R.move_as_ok().serialize() + ".adnl";
                    td::actor::send_closure(SelfId, &DNSResolver::save_to_cache, full_host, final_address);
                    promise.set_result(std::move(final_address));
                  } else {
                    promise.set_error(R.move_as_error_prefix("Failed to parse ADNL address: "));
                  }
                },
                // --- CASE C: FINAL ANSWER (Storage Bag ID) ---
                [&](tonlib_api::dns_entryDataStorageAddress &x) {
                    LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] SUCCESS: Found final Storage address: " << td::to_lower(x.bag_id_.to_hex());
                    std::string final_address = td::to_lower(x.bag_id_.to_hex()) + ".bag";
                    td::actor::send_closure(SelfId, &DNSResolver::save_to_cache, full_host, final_address);
                    promise.set_result(std::move(final_address));
                },
                // --- CASE D: UNHANDLED RECORD (End of the line) ---
                [&](auto &x) {
                    LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: Unsupported record type returned for " << full_host;
                    if (promise) {
                        promise.set_error(td::Status::Error(
                            "DNS resolution failed: unsupported or no final record type returned"));
                    }
                }
            ));
      });

  td::actor::send_closure(tonlib_client_, &tonlib::TonlibClientWrapper::send_request<tonlib_api::dns_resolve>,
                          std::move(obj), std::move(P));
}

void DNSResolver::save_to_cache(std::string host, std::string address) {
  CacheEntry &entry = cache_[host];
  entry.address_ = address;
  entry.created_at_ = td::Time::now();
}
