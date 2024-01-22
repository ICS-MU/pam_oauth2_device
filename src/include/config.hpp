#ifndef PAM_OAUTH2_DEVICE_CONFIG_HPP
#define PAM_OAUTH2_DEVICE_CONFIG_HPP

#include <map>
#include <set>
#include <string>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

class Config {
 public:
  void load(const char *path);
  std::string client_id, client_secret, scope, device_endpoint, token_endpoint,
      userinfo_endpoint, username_attribute, ldap_basedn, ldap_user,
      ldap_passwd, ldap_filter, ldap_attr;
  bool require_mfa, qr_show;
  std::set<std::string> ldap_hosts;
  int qr_error_correction_level;
  std::map<std::string, std::set<std::string>> usermap;
 private:
  void fill_user_map_from_json(std::map<std::string, std::set<std::string>>& user_map, json& j);
};

#endif  // PAM_OAUTH2_DEVICE_CONFIG_HPP
