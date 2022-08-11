###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0006_remote.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# VMSA-2014-0006: VMware product updates address OpenSSL security vulnerabilities (remote check)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105045");
  script_cve_id("CVE-2014-0224", "CVE-2014-0198", "CVE-2010-5298", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11867 $");
  script_name("VMSA-2014-0006: VMware product updates address OpenSSL security vulnerabilities (remote check)");


  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-13 11:04:01 +0100 (Fri, 13 Jun 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Check the build number");
  script_tag(name:"insight", value:"a. OpenSSL update for multiple products.

OpenSSL libraries have been updated in multiple products to versions 0.9.8za and 1.0.1h
in order to resolve multiple security issues.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"summary", value:"VMware product updates address OpenSSL security vulnerabilities.");
  script_tag(name:"affected", value:"ESXi 5.5 prior to ESXi550-201406401-SGi,
ESXi 5.1 without patch ESXi510-201406401-SG,
ESXi 5.0 without patch ESXi500-201407401-SG");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

 exit(0);

}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0","1881737",
                           "5.1.0","1900470",
                           "5.0.0","1918656");

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message(port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );

