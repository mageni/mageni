###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_rce_vuln1.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# FreePBX Remote Command Execution Vulnerability
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

CPE = 'cpe:/a:freepbx:freepbx';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106318");
  script_version("$Revision: 12083 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-30 10:47:53 +0700 (Fri, 30 Sep 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_detect.nasl");
  script_mandatory_keys("freepbx/installed");

  script_tag(name:"summary", value:"FreePBX is prone to a unauthenticated remote command execution
  vulnerability.");

  script_tag(name:"insight", value:"Freepbx is vulnerable to unauthenticated remote command execution in the
  Hotel Wakeup module.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may execute arbitrary commands.");

  script_tag(name:"affected", value:"FreePBX version 13.x");

  script_tag(name:"solution", value:"Upgrade to version 13.0.188.1 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40434/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version and the Hotel Wakeup module is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];

if (version =~ "^13\.") {
  if (version_is_less(version: version, test_version: "13.0.188.1")) {

    if( !dir = infos['location'] )
      exit(0);

    if (dir == "/")
      dir = "";

    host = http_host_name(port: port);

    url = dir + "/admin/ajax.php";
    data = 'module=hotelwakeup&command=savecall';

    req = http_post_req(port: port, url: url, data: data,
                        add_headers: make_array("Referer", "http://" + host + "/"));
    res = http_keepalive_send_recv(port: port, data: req);

    if ("Referrer" >< res) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.0.188.1");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
