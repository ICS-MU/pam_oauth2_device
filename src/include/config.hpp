#ifndef PAM_OAUTH2_DEVICE_CONFIG_HPP
#define PAM_OAUTH2_DEVICE_CONFIG_HPP

#include <map>
#include <set>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

class Config {
 public:
  // OAuth2
  std::string client_id;
  std::string client_secret;
  std::string scope;
  std::string device_endpoint;
  std::string token_endpoint;
  std::string userinfo_endpoint;
  std::string username_attribute;
  bool require_mfa;

  // QR code
  bool qr_show;
  int qr_error_correction_level;

  // LDAP
  std::string ldap_basedn;
  std::string ldap_user;
  std::string ldap_passwd;
  std::string ldap_filter;
  std::string ldap_attr;
  std::set<std::string> ldap_hosts;

  // usermap
  std::map<std::string, std::set<std::string>> usermap;

  // functions
  void load(const char *path);
 private:
  static void fill_user_map_from_json(std::map<std::string, std::set<std::string>>& user_map, json& j);
};

#endif  // PAM_OAUTH2_DEVICE_CONFIG_HPP
