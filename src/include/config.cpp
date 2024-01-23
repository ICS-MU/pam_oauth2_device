#include "config.hpp"

#include <fstream>
#include <set>
#include <syslog.h>

#include "nlohmann/json.hpp"

using namespace std;
using json = nlohmann::json;

void Config::load(const char *path) {
  ifstream config_fstream(path);
  json j;
  config_fstream >> j;
  
  json oauth_json = j.at("oauth");

  client_id = oauth_json.at("client").at("id").get<string>();
  client_secret = oauth_json.at("client").at("secret").get<string>();
  scope = oauth_json.at("scope").get<string>();
  device_endpoint = oauth_json.at("device_endpoint").get<string>();
  token_endpoint = oauth_json.at("token_endpoint").get<string>();
  userinfo_endpoint = oauth_json.at("userinfo_endpoint").get<string>();
  username_attribute = oauth_json.at("username_attribute").get<string>();
  require_mfa = oauth_json.contains("require_mfa") && oauth_json.at("require_mfa").get<bool>();
  
  json qr_json = j.at("qr");
  qr_error_correction_level =
      qr_json.at("error_correction_level").get<int>();
  qr_show = qr_json.contains("show") && qr_json.at("show").get<bool>();

  if (j.find("ldap") != j.end() && j.at("ldap").find("hosts") != j.at("ldap").end()) {
    json ldap_json = j.at("ldap");
    for (auto const &host : ldap_json.at("hosts")) {
      ldap_hosts.insert((string)host);
    }
    ldap_basedn = ldap_json.at("basedn").get<string>();
    ldap_user = ldap_json.at("user").get<string>();
    ldap_passwd = ldap_json.at("passwd").get<string>();
    ldap_filter = ldap_json.at("filter").get<string>();
    ldap_attr = ldap_json.at("attr").get<string>();
  }

  json users_json;
  if (j.find("users") != j.end()) {
    users_json = j.at("users");
    Config::fill_user_map_from_json(users_json);
  } else if (j.find("usersFilePath") != j.end()) {
    string users_path = j.at("usersFilePath").get<string>();
    ifstream users_fstream(users_path);
    users_fstream >> users_json;
    Config::fill_user_map_from_json(users_json);
  }
}

void Config::fill_user_map_from_json(json& j) {
  for (auto const &element : j["users"].items()) {
    for (auto const &local_user : element.value()) {
      if (usermap.find(element.key()) == usermap.end()) {
        set<string> userset;
        usermap[element.key()] = userset;
      }
      usermap[element.key()].insert((string)local_user);
    }
  }
}
