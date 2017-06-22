//
// Created by mtakigiku on 6/21/17.
//
#include <string>

#include "common/common/base64.h"
#include "common/common/logger.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "envoy/server/instance.h"
#include "envoy/ssl/connection.h"
#include "server/config/network/http_connection_manager.h"

#include "envoy/server/instance.h"
//#include "envoy/server/filter_config.h"
#include "server/config/network/http_connection_manager.h"


namespace Envoy{
namespace Http{
namespace TestFilter{

class Config {
 public:
  Config(const Json::Object& config){
  }
};
typedef std::shared_ptr<Config> ConfigPtr;

class Instance : public Http::StreamDecoderFilter {
 public:
  Instance(ConfigPtr config) {
  }
  ~Instance(){}

  void onDestroy() override {}

  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool end_stream) override{
    return FilterHeadersStatus::Continue;
  }

  FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override{
    return FilterDataStatus::Continue;
  }
  FilterTrailersStatus decodeTrailers(HeaderMap& trailers) override {
    return FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }

 private:
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  ConfigPtr config_;
};

} // TestFilter
} // Http

namespace Server{
namespace Configuration {

class TestFilterConfig : public NamedHttpFilterConfigFactory {
 public:
  HttpFilterFactoryCb createFilterFactory(
      HttpFilterType type,
      const Json::Object& config,
      const std::string& stat_prefix,
      Server::Instance& server) override{
      // Envoy::Server::Configuration::FactoryContext& context) override{

    if (type != HttpFilterType::Decoder)
      return nullptr;
    Http::TestFilter::ConfigPtr test_config(
        new Http::TestFilter::Config(config));

    return
        [test_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
            callbacks.addStreamDecoderFilter(
                Http::StreamDecoderFilterSharedPtr{new Http::TestFilter::Instance(test_config)}
            );
        };

  }
  std::string name() override { return "test"; }
  // HttpFilterType type() override { return HttpFilterType::Decoder; }
};

} // Configuration
} // Server
} // Envoy