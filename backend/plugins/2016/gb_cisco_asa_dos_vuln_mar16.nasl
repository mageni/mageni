###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_dos_vuln_mar16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco ASA 5500 Devices Denial of Service Vulnerability - Mar16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806690");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-1312");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-22 12:49:04 +0530 (Tue, 22 Mar 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA 5500 Devices Denial of Service Vulnerability - Mar16");

  script_tag(name:"summary", value:"This host is running Cisco ASA 5500 device
  which is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the HTTPS
  inspection engine of the Cisco ASA Content Security and Control Security Services
  Module (CSC-SSM) which improperly handles HTTPS packets transiting through the
  affected system.");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker
  to cause exhaustion of available memory, system instability, and a reload of
  the affected system.");

  script_tag(name:"affected", value:"Cisco ASA 5500-X Series Firewalls with
  software version 6.6.x prior to 6.6.1164.0

  - ---
  NOTE:Cisco ASA 5500-X Series Firewalls with version 6.6.1157.0 is not vulnerable

  - ---");

  script_tag(name:"solution", value:"Upgrade to the software version 6.6.1164.0
  or later. For more details");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCue76147");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160309-csc");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl");
  script_mandatory_keys("cisco_asa/version", "cisco_asa/model");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

model = get_kb_item("cisco_asa/model");
if(!model || toupper(model) !~ "^ASA55[0-9][0-9]"){
  exit(0);
}

if(!cisVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Replace parenthesis with .
cisVer = ereg_replace(string:cisVer, pattern:"\(([0-9.]+)\)", replace:".\1");

if(cisVer =~ "^(6.6)")
{
  ##6.6.1157.0 is not vulnerable
  if(version_is_equal(version:cisVer, test_version:"6.6.1157.0")){
    exit(0);
  }

  if(version_is_less(version:cisVer, test_version:"6.6.1164.0"))
  {
    report = report_fixed_ver(installed_version:cisVer, fixed_version:"6.6.1164.0");
    security_message(data:report);
    exit(0);
  }
}
