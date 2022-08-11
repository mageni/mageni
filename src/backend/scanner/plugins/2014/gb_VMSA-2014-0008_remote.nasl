###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0008_remote.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# VMSA-2014-0008: VMware vSphere product updates to third party libraries ((remote check))
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105087");
  script_cve_id("CVE-2014-0114", "CVE-2013-4590", "CVE-2013-4322", "CVE-2014-0050", "CVE-2013-0242", "CVE-2013-1914");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11867 $");
  script_name("VMSA-2014-0008: VMware vSphere product updates to third party libraries (remote check)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");
  script_tag(name:"vuldetect", value:"Check the build number");
  script_tag(name:"insight", value:"a. vCenter Server Apache Struts Update

The Apache Struts library is updated to address a security issue.
This issue may lead to remote code execution after authentication.

b. vCenter Server tc-server 2.9.5 / Apache Tomcat 7.0.52 updates

tc-server has been updated to version 2.9.5 to address multiple security issues.
This version of tc-server includes Apache Tomcat 7.0.52.

c. Update to ESXi glibc package

glibc is updated to address multiple security issues.

d. vCenter and Update Manager, Oracle JRE 1.7 Update 55

Oracle has documented the CVE identifiers that are addressed in JRE 1.7.0
update 55 in the Oracle Java SE Critical Patch Update Advisory of April 2014");

  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"summary", value:"VMware has updated vSphere third party libraries");

  script_tag(name:"affected", value:"VMware vCenter Server 5.5 prior to Update 2
VMware vCenter Update Manager 5.5 prior to Update 2
VMware ESXi 5.5 without patch ESXi550-201409101-SG");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-11 11:04:01 +0100 (Thu, 11 Sep 2014)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

exit(0);

}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0","2068190",
                           "5.1.0", "2323231");

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message(port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );

