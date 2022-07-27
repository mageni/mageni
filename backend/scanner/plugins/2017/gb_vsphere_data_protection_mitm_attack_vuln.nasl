###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsphere_data_protection_mitm_attack_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# VMware vSphere Data Protection (VDP) Man-in-the-Middle Attack Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:vmware:vsphere_data_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810683");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2014-4632");
  script_bugtraq_id(72367);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-11 12:14:20 +0530 (Tue, 11 Apr 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("VMware vSphere Data Protection (VDP) Man-in-the-Middle Attack Vulnerability");

  script_tag(name:"summary", value:"This host is installed with  VMware vSphere
  Data Protection (VDP) and is prone to a man in the middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper verification
  of X.509 certificates from vCenter Server SSL servers.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof servers, and bypass intended backup and restore access
  restrictions, via a crafted certificate.");

  script_tag(name:"affected", value:"VMware vSphere Data Protection (VDP) 5.1,
  5.5 before 5.5.9, and 5.8 before 5.8.1");

  script_tag(name:"solution", value:"Upgrade to VMware vSphere Data Protection
  (VDP) 5.5.9 or 5.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0002.html");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031664");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_vsphere_data_protection_version.nasl");
  script_mandatory_keys("vmware/vSphere_Data_Protection/version");
  script_xref(name:"URL", value:"http://www.vmware.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(appVer =~ "^5\.1\.")
{
  VULN = TRUE;
  fix = "5.5.9 or 5.8.1";
}
else if((appVer =~ "^5\.5\.") && (version_is_less(version:appVer, test_version:"5.5.9")))
{
  VULN = TRUE;
  fix = "5.5.9";
}
else if((appVer =~ "^5\.8\.") && (version_is_less(version:appVer, test_version:"5.8.1")))
{
  VULN = TRUE;
  fix = "5.8.1";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
