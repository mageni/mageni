# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140853");
  script_version("2020-11-02T15:23:18+0000");
  script_tag(name:"last_modification", value:"2020-11-12 11:33:03 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-22 11:53:03 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("Backup File Scanner (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify backup files left on the web server.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the following
  VTs (depending on the reliability of the detection):

  - 'Backup File Scanner (HTTP) - Unreliable Detection Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108975)

  - 'Backup File Scanner (HTTP) - Reliable Detection Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108976)");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if backup files are
  accessible.");

  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might be able to
  gather sensitive information stored in these files.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/10/31/1");

  script_add_preference(name:"Backup File Extensions", type:"entry", value:".backup, .bak, .copy, .bkp, .old, .orig, .temp, .tmp, ~, .swp, .save", id:1);

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

extensions = script_get_preference("Backup File Extensions", id:1);
if (strlen(extensions) > 0) {
  extensions = str_replace(string: extensions, find: " ", replace: "");
  extensions = split(extensions, sep: ",", keep: FALSE);
  extensions = make_list_unique(extensions);
} else {
  extensions = make_list(".backup", ".bak", ".copy", ".bkp", ".old", ".orig", ".temp", ".tmp", "~", ".swp", ".save");
}

default_php_files = make_list("/index.php", "/wp-config.php", "/configuration.php",
                              "/config.php", "/config.inc.php", "/settings.php");

file_list = make_list();
check_info_array = make_array();
check_info_array["php"] = "^<\?(php|=)#-----#reliable#-----#bodyonly";
check_info_array["other"] = "^HTTP/1\.[01] 200#-----#unreliable#-----#bodyndheader";

port = http_get_port(default: 80);
host = http_host_name(dont_add_port: TRUE);

set_kb_item(name: "http_backup_file_scan/started", value: TRUE);

dirs = make_list_unique("/", http_cgi_dirs(port: port, host: host));
foreach dir(dirs) {

  if (dir == "/")
    dir = "";

  foreach default_php_file(default_php_files)
    file_list = make_list(file_list, dir + default_php_file);
}

# TBD: Use host: "*" ?
kb_file_list = http_get_kb_file_extensions(port: port, host: host, ext: "*");
if (kb_file_list)
  file_list = make_list(file_list, kb_file_list);

file_list = make_list_unique(file_list);
foreach file (file_list) {

  ext = ereg_replace(pattern:".*\.([^\.]*)$", string:file, replace:"\1");
  if (!ext)
    continue;

  check_info = check_info_array[ext];
  if (!check_info) {
    check_info = check_info_array["other"];
    if (!check_info)
      continue;
  }

  check_info_split = split(check_info, sep: "#-----#", keep: FALSE);
  if (!check_info_split || max_index(check_info_split) != 3)
    continue;

  pattern = check_info_split[0];

  qod = check_info_split[1];
  if (qod == "reliable")
    set_kb_key = "www/" + host + "/" + port + "/content/backup_file_reliable";
  else
    set_kb_key = "www/" + host + "/" + port + "/content/backup_file_unreliable";

  bodyonly = check_info_split[2];
  if (bodyonly == "bodyonly")
    bodyonly = TRUE;
  else
    bodyonly = FALSE;

  foreach ext (extensions) {
    url = file + ext;
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: bodyonly);

    if (res && eregmatch(string: res, pattern: pattern, icase: FALSE))
      set_kb_item(name: set_kb_key, value: http_report_vuln_url(port: port, url: url, url_only: TRUE) + "#-----#" + pattern);

    # try as well "hidden" files like '/.file.ext'
    path = split(file, sep: "/", keep: TRUE);
    filename = path[max_index(path) - 1];
    if (!filename)
      continue;

    url = ereg_replace(pattern: filename, string: file, replace: '.' + filename + ext);
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: bodyonly);

    if (res && eregmatch(string: res, pattern: pattern, icase: FALSE))
      set_kb_item(name: set_kb_key, value: http_report_vuln_url(port: port, url: url, url_only: TRUE) + "#-----#" + pattern);
  }
}

set_kb_item( name:"http_backup_file_scan/" + host + "/" + port + "/no_timeout", value: TRUE);

exit(0);
