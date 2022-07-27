###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ip_phone_xss_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco IP Phone 8800 Series Cross-Site Scripting Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106176");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-11 13:36:26 +0700 (Thu, 11 Aug 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2016-1476");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IP Phone 8800 Series Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"Cisco IP Phone 8800 Series are prone to a cross site scripting
vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of parameter values.
An attacker could exploit this vulnerability by storing malicious code on a device and waiting for a user
to access a web page that triggers execution of the code.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary script code
in the context of the web interface on the affected device.");

  script_tag(name:"affected", value:"Cisco IP Phone 8800 Series version 11.0 is affected");

  script_tag(name:"solution", value:"Upgrade to version 11.5(1)ES6 or 11.7(1)MN694 or later.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160810-ip-phone-8800");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-88..") {
  if (model =~ "^CP-8831" || model =~ "^CP-8821" || model =~ "^CP-8825")
    exit(0);

  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip88xx\.([0-9-]+)", string: version);
  if (version[1] && version[1] =~ "^11-0") {
    security_message(port: 0);
  }
}

exit(0);
