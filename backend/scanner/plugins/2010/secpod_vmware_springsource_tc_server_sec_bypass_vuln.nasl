###############################################################################
# OpenVAS Vulnerability Test
#
# SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902188");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1454");
  script_bugtraq_id(40205);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_vmware_springsource_tc_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("vmware/tc_server/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain JMX interface access
  via a blank password.");

  script_tag(name:"affected", value:"VMware SpringSource tc Server Runtime 6.0.19 and 6.0.20 before 6.0.20.D and
  6.0.25.A before 6.0.25.A-SR01.");

  script_tag(name:"insight", value:"The flaw is cused due to error in,
  'com.springsource.tcserver.serviceability.rmi.JmxSocketListener', if the
  listener is configured to use an encrypted password then entering either the
  correct password or an empty string will allow authenticated access to the
  JMX interface.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to SpringSource tc Server Runtime to 6.0.20.D or 6.0.25.A-SR01.");

  script_tag(name:"summary", value:"This host is running SpringSource tc Server and is prone to security
  bypass vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39778");
  script_xref(name:"URL", value:"http://www.springsource.com/security/cve-2010-1454");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

sstcPort = get_http_port(default:8080);

sstcVer = get_kb_item(string("www/", sstcPort, "/Vmware/SSTC/Runtime"));
if(isnull(sstcVer))
  exit(0);

sstcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sstcVer);
if(isnull(sstcVer[1]))
  exit(0);

if(version_is_equal(version:sstcVer[1], test_version:"6.0.19") ||
   version_in_range(version:sstcVer[1], test_version:"6.0.20", test_version2:"6.0.20.C") ||
   version_in_range(version:sstcVer[1], test_version:"6.0.25", test_version2:"6.0.25.A.SR00")){
  security_message(sstcPort);
}
