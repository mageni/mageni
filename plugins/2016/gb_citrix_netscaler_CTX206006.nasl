###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CTX206006.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Citrix NetScaler Service Delivery Appliance Multiple Security Updates
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105841");
  script_cve_id("CVE-2015-4163", "CVE-2015-4106", "CVE-2015-4105", "CVE-2015-4104", "CVE-2015-4103", "CVE-2015-2756");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12363 $");

  script_name("Citrix NetScaler Service Delivery Appliance Multiple Security Updates (CTX206006)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX206006");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:
CVE-2015-4163: GNTTABOP_swap_grant_ref operation misbehaviour
CVE-2015-4106: Unmediated PCI register access in qemu
CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error messages
CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests
CVE-2015-4103: Potential unintended writes to host MSI message data field via qemu
CVE-2015-2756: Unmediated PCI command register access in qemu");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"A number of vulnerabilities have been identified in the Citrix NetScaler Service Delivery Appliance (SDX) that could allow a malicious administrative user to crash the host or other VMs and execute arbitrary code on the SDX host.");

  script_tag(name:"affected", value:"Version 10.5 and 10.5e earlier than 10.5 Build 58.11 and 10.5 Build 57.7005.e and Version 10.1 earlier than 10.1 Build 133.9");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-01 13:12:14 +0200 (Mon, 01 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_citrix_netscaler_version.nasl");
  script_mandatory_keys("citrix_netscaler/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );

if( get_kb_item( "citrix_netscaler/enhanced_build" ) ) enhanced = TRUE;

if( enhanced )
{
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.57.7004" ) )
  {
    fix = '10.5 Build 57.7005.e';
    vers = vers + '.e';
  }
}
else
{
  if( version_in_range( version:vers, test_version:'10.5', test_version2:'10.5.58.10' ) )
  {
    fix = '10.5 Build 58.11';
  }

  if( version_in_range( version:vers, test_version:'10.1', test_version2:'10.1.133.8' ) )
  {
    fix = '10.1 build 133.9';
  }
}

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

