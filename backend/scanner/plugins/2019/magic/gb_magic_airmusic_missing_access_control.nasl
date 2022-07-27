# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:magic:airmusic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108651");
  script_version("2019-09-18T13:31:29+0000");
  script_cve_id("CVE-2019-13474");
  script_tag(name:"last_modification", value:"2019-09-18 13:31:29 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-03-17 11:11:44 +0100 (Sun, 17 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Magic AirMusic Insufficient Access Control Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_magic_airmusic_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magic/airmusic/detected");

  script_xref(name:"URL", value:"https://www.vulnerability-db.com/?q=articles/2019/09/09/imperial-dabman-internet-radio-undocumented-telnetd-code-execution");
  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2183");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/Sep/12");

  script_tag(name:"summary", value:"Various products of multiple vendors using the Magic AirMusic web interface for
  the control of the device are prone to an insufficient access control vulnerability.");

  script_tag(name:"impact", value:"In the worst case a remote attacker could modify the system to spread remotly
  ransomware or other malformed malicious viruses / rootkits / destruktive scripts. He can aslso use the web-server
  to be part of a iot botnet.");

  script_tag(name:"affected", value:"TELESTAR Bobs Rock Radio, Dabman D10, Dabman i30 Stereo, Imperial i110, Imperial i150,
  Imperial i200, Imperial i200-cd, Imperial i400, Imperial i450, Imperial i500-bt, and Imperial i600 devices are known to be
  affected. Other devices and vendors might be affected as well.");

  script_tag(name:"solution", value:"According to the security researcher the vendor TELESTAR has released the firmware update
  TN81HH96-g102h-g103**a*-fb21a-3624 which is mitigating this vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# nb: playinfo and hotkeylist seems to be not available on all devices.
# The stop command was always available so try this as the last resort
# as all other commands which could be used are writing to the device.
foreach cmd( make_list( "playinfo", "hotkeylist", "stop" ) ) {

  url = dir + "/" + cmd;

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  # Possible returns:
  # <?xml version="1.0" encoding="UTF-8"?><result>FAIL</result>
  # <?xml version="1.0" encoding="UTF-8"?><result><rt>INVALID_CMD</rt></result>
  # <?xml version="1.0" encoding="UTF-8"?><result>OK</result>
  # <?xml version="1.0" encoding="UTF-8"?><menu><item_total>5</item_total><item_return>5</item_return><item><id>75_0</id><status>emptyfile</status><name>Pusta</name></item><item><id>75_1</id><status>emptyfile</status><name>Pusta</name></item><item><id>75_2</id><status>emptyfile</status><name>Pusta</name></item><item><id>75_3</id><status>emptyfile</status><name>Pusta</name></item><item><id>75_4</id><status>emptyfile</status><name>Pusta</name></item></menu>

  if( "<result>OK</result>" >< res || "<menu><item_total>" >< res || "<result>FAIL</result>" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
