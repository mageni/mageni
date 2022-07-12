###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Prime Collaboration Assurance Multiple Vulnerabilities - Mar17
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:cisco:prime_collaboration_assurance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810677");
  script_version("2019-05-03T10:12:14+0000");
  script_cve_id("CVE-2017-3843", "CVE-2017-3844", "CVE-2017-3845");
  script_bugtraq_id(96248, 96247, 96245);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:12:14 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-23 10:34:46 +0530 (Thu, 23 Mar 2017)");
  script_name("Cisco Prime Collaboration Assurance Multiple Vulnerabilities - Mar17");

  script_tag(name:"summary", value:"This host is running cisco prime collaboration
  assurance and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The lack of proper input validation of HTTP requests.

  - An insufficient validation of user-supplied input by the web-based management
    interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to view file directory listings and download files, conduct a
  cross-site scripting (XSS) attack and download system files that should be
  restricted.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"affected", value:"Cisco Prime Collaboration Assurance
  versions 11.0.0, 11.1.0 and 11.5.0");

  script_tag(name:"solution", value:"Apply patch from the vendor advisory.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-pcp2");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-pcp3");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_pca_version.nasl");
  script_mandatory_keys("cisco_pcp/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE)) exit(0);

if(version =~ "^11\.[015]")
{
  if(version_is_equal(version:version, test_version:"11.0.0")||
     version_is_equal(version:version, test_version:"11.1.0")||
     version_is_equal(version:version, test_version:"11.5.0"))
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"Apply Patch");
    security_message(data:report, port:0);
    exit(0);
  }
}

exit(0);