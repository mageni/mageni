###############################################################################
# OpenVAS Vulnerability Test
#
# Tembria Server Monitor HTTP Request Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901104");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1316");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Tembria Server Monitor HTTP Request Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39270");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/advisories.php?id=CORELAN-10-022");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_tembria_server_monitor_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tembria/server_monitor/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Tembria Server Monitor 5.6.0 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in the processing of 'HTTP' requests that
  allow attackers to terminate the webserver via a malformed HTTP GET request.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade Tembria Server Monitor version 5.6.1.");

  script_tag(name:"summary", value:"The host is running Tembria Server Monitor and is prone to Denial
  of Service vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

ver = get_kb_item("www/" + port + "/tembria");
tembriaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(tembriaVer[1])
{
   if(version_is_less(version:tembriaVer[1], test_version:"5.6.1")){
     security_message(port);
   }
}
