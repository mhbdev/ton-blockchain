#pragma once
#include "td/actor/actor.h"
#include "tonlib/tonlib/TonlibClientWrapper.h"
#include "adnl/adnl.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/crypto.h"
#include <vector>
#include <map>
#include <string>

class DNSResolver : public td::actor::Actor {
public:
  explicit DNSResolver(td::actor::ActorId<tonlib::TonlibClientWrapper> tonlib_client);

  void start_up() override;
  void resolve(std::string host, td::Promise<std::string> promise);

private:
  static constexpr uint16_t CATEGORY_NEXT_RESOLVER = 0xba93;
  static constexpr uint16_t CATEGORY_CONTRACT_ADDR = 0x9fd3;
  static constexpr uint16_t CATEGORY_ADNL_SITE = 0xad01;
  static constexpr uint16_t CATEGORY_STORAGE_SITE = 0x7473;

  static constexpr int MAX_DNS_HOPS = 4;

  void sync();
  void save_to_cache(std::string host, std::string address);

  void resolve_recursive(std::string full_host,
                         std::vector<uint8_t> domain_chain,
                         tonlib_api::object_ptr<tonlib_api::accountAddress> resolver_address,
                         int depth,
                         td::Promise<std::string> promise);

  std::vector<uint8_t> prepare_domain_name(const std::string& domain);
  td::Bits256 calculate_record_hash(const std::string& record_name);

  // helper to forward smc_runGetMethod
  void forward_runGetMethod(tonlib_api::object_ptr<tonlib_api::smc_runGetMethod> run_obj,
                            td::Promise<tonlib_api::object_ptr<tonlib_api::smc_runResult>> run_promise);

  td::actor::ActorId<tonlib::TonlibClientWrapper> tonlib_client_;

  struct CacheEntry {
    std::string address_;
    double created_at_;
  };
  std::map<std::string, CacheEntry> cache_;
};
