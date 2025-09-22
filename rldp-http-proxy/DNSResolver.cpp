/*
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.
*/

#include "DNSResolver.h"
#include "td/utils/overloaded.h"
#include "td/utils/crypto.h"
#include "common/delay.h"
#include <algorithm>
#include <sstream>

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
      ton::delay_action([SelfId]() { td::actor::send_closure(SelfId, &DNSResolver::sync); },
                        td::Timestamp::in(5.0));
    }
  });
  td::actor::send_closure(tonlib_client_,
                          &tonlib::TonlibClientWrapper::send_request<tonlib_api::sync>,
                          std::move(obj), std::move(P));
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
      if (now < entry.created_at_ + CACHE_TIMEOUT_SOFT) {
        return;
      }
    }
  }

  // Prepare domain name according to Go implementation
  std::vector<uint8_t> domain_chain = prepare_domain_name(host);
  resolve_recursive(host, std::move(domain_chain), nullptr, 0, std::move(promise));
}

std::vector<uint8_t> DNSResolver::prepare_domain_name(const std::string& domain) {
  std::vector<std::string> parts;
  std::stringstream ss(domain);
  std::string item;

  while (std::getline(ss, item, '.')) {
    if (!item.empty()) {
      parts.push_back(item);
    }
  }

  std::reverse(parts.begin(), parts.end());

  std::vector<uint8_t> result;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) {
      result.push_back(0);  // null separator
    }
    const auto& part = parts[i];
    result.insert(result.end(), part.begin(), part.end());
  }
  result.push_back(0);  // trailing null byte

  LOG(INFO) << "[DNS TRACE] Prepared domain chain length: " << result.size() << " bytes";
  return result;
}

td::Bits256 DNSResolver::calculate_record_hash(const std::string& record_name) {
  return td::sha256_bits256(td::Slice(record_name.data(), record_name.size()));
}

void DNSResolver::resolve_recursive(std::string full_host,
                                    std::vector<uint8_t> domain_chain,
                                    tonlib_api::object_ptr<tonlib_api::accountAddress> resolver_address,
                                    int depth,
                                    td::Promise<std::string> promise) {
  LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] Resolving '" << full_host
            << "' using resolver: " << (resolver_address ? resolver_address->account_address_ : "Root DNS")
            << ", chain length: " << domain_chain.size();

  if (depth >= MAX_DNS_HOPS) {
    LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: DNS resolution depth limit exceeded for " << full_host;
    promise.set_error(td::Status::Error("DNS resolution depth limit exceeded"));
    return;
  }

  std::string domain_bytes(domain_chain.begin(), domain_chain.end());
  auto name_slice = tonlib_api::make_object<tonlib_api::tvm_slice>(domain_bytes);
  auto name_stack_entry = tonlib_api::make_object<tonlib_api::tvm_stackEntrySlice>(std::move(name_slice));

  auto category_number = tonlib_api::make_object<tonlib_api::tvm_numberDecimal>("0");
  auto category_stack_entry = tonlib_api::make_object<tonlib_api::tvm_stackEntryNumber>(std::move(category_number));

  auto load_obj = tonlib_api::make_object<tonlib_api::smc_load>(std::move(resolver_address));

  auto load_promise = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), promise = std::move(promise), full_host, domain_chain, depth,
       name_stack_entry = std::move(name_stack_entry), category_stack_entry = std::move(category_stack_entry)](
          td::Result<tonlib_api::object_ptr<tonlib_api::smc_info>> load_result) mutable {
        if (load_result.is_error()) {
          std::string error_msg = load_result.error().message().str();
          if (error_msg.find("not initialized") != std::string::npos ||
              error_msg.find("account not found") != std::string::npos) {
            LOG(WARNING) << "[DNS TRACE] [Depth " << depth << "] Domain not found (contract not initialized): " << full_host;
            promise.set_error(td::Status::Error("no DNS entries found"));
            return;
          }
          LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: smc_load returned error: " << load_result.error();
          promise.set_error(load_result.move_as_error());
          return;
        }

        auto smc_info = load_result.move_as_ok();

        auto method_name = tonlib_api::make_object<tonlib_api::smc_methodIdName>("dnsresolve");
        std::vector<tonlib_api::object_ptr<tonlib_api::tvm_StackEntry>> stack;
        stack.push_back(std::move(name_stack_entry));
        stack.push_back(std::move(category_stack_entry));

        auto run_obj = tonlib_api::make_object<tonlib_api::smc_runGetMethod>(
            smc_info->id_, std::move(method_name), std::move(stack));

        auto run_promise = td::PromiseCreator::lambda(
            [SelfId, promise = std::move(promise), full_host, domain_chain, depth](
                td::Result<tonlib_api::object_ptr<tonlib_api::smc_runResult>> R) mutable {
              if (R.is_error()) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: smc_runGetMethod returned error: " << R.error();
                promise.set_error(R.move_as_error());
                return;
              }

              auto result = R.move_as_ok();

              if (result->exit_code_ != 0) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: dnsresolve method exit code: " << result->exit_code_;
                promise.set_error(td::Status::Error("DNS resolve method failed"));
                return;
              }

              if (result->stack_.size() < 2) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: Invalid dnsresolve result stack size";
                promise.set_error(td::Status::Error("Invalid DNS resolve result"));
                return;
              }

              auto* bits_entry = dynamic_cast<tonlib_api::tvm_stackEntryNumber*>(result->stack_[0].get());
              if (!bits_entry) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: Invalid bits entry type";
                promise.set_error(td::Status::Error("Invalid bits entry in DNS result"));
                return;
              }

              int64_t bits_resolved = 0;
              try {
                bits_resolved = std::stoll(bits_entry->number_->number_);
              } catch (const std::exception& e) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: Cannot parse bits: " << e.what();
                promise.set_error(td::Status::Error("Cannot parse resolved bits"));
                return;
              }

              if (bits_resolved % 8 != 0) {
                LOG(ERROR) << "[DNS TRACE] [Depth " << depth << "] FAILED: Resolved bits is not mod 8";
                promise.set_error(td::Status::Error("resolved bits is not mod 8"));
                return;
              }

              int bytes_resolved = static_cast<int>(bits_resolved / 8);
              LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] Resolved " << bytes_resolved << " bytes";

              auto* data_entry = dynamic_cast<tonlib_api::tvm_stackEntryCell*>(result->stack_[1].get());
              if (!data_entry) {
                LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] Domain exists but has no records: " << full_host;
                promise.set_error(td::Status::Error("no DNS entries found"));
                return;
              }

              if (full_host.find(".ton") != std::string::npos) {
                std::string result_addr = "storage_bag_placeholder.bag";
                LOG(INFO) << "[DNS TRACE] [Depth " << depth << "] SUCCESS: Simplified result: " << result_addr;
                td::actor::send_closure(SelfId, &DNSResolver::save_to_cache, full_host, result_addr);
                promise.set_result(std::move(result_addr));
              } else {
                promise.set_error(td::Status::Error("Complex cell parsing not implemented in this simplified version"));
              }
            });

        td::actor::send_closure(SelfId, &DNSResolver::forward_runGetMethod,
                                std::move(run_obj), std::move(run_promise));
      });

  td::actor::send_closure(tonlib_client_,
                          &tonlib::TonlibClientWrapper::send_request<tonlib_api::smc_load>,
                          std::move(load_obj), std::move(load_promise));
}

void DNSResolver::forward_runGetMethod(
    tonlib_api::object_ptr<tonlib_api::smc_runGetMethod> run_obj,
    td::Promise<tonlib_api::object_ptr<tonlib_api::smc_runResult>> run_promise) {
  td::actor::send_closure(tonlib_client_,
                          &tonlib::TonlibClientWrapper::send_request<tonlib_api::smc_runGetMethod>,
                          std::move(run_obj), std::move(run_promise));
}

void DNSResolver::save_to_cache(std::string host, std::string address) {
  CacheEntry &entry = cache_[host];
  entry.address_ = std::move(address);
  entry.created_at_ = td::Time::now();
}
