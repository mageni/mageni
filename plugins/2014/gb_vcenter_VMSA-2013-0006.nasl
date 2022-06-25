###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2013-0006.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# VMware Security Updates for vCenter Server (VMSA-2013-0006)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103873");
  script_cve_id("CVE-2013-3107", "CVE-2012-2733", "CVE-2012-4534");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 14185 $");
  script_name("VMware Security Updates for vCenter Server (VMSA-2013-0006)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0006.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-09 12:04:01 +0100 (Thu, 09 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

  script_tag(name:"vuldetect", value:"Check the build number.");

  script_tag(name:"insight", value:"vCenter Server AD anonymous LDAP binding credential by-pass

  vCenter Server when deployed in an environment that uses Active Directory (AD)
  with anonymous LDAP binding enabled doesn't properly handle login credentials.
  In this environment, authenticating to vCenter Server with a valid user name
  and a blank password may be successful even if a non-blank password is required
  for the account.

  The issue is present on vCenter Server 5.1, 5.1a and 5.1b if AD anonymous LDAP
  binding is enabled. The issue is addressed in vCenter Server 5.1 Update 1 by
  removing the possibility to authenticate using blank passwords. This change in
  the authentication mechanism is present regardless if anonymous  binding is
  enabled or not.

  Workaround

  The workaround is to discontinue the use of AD anonymous LDAP binding if it is
  enabled in your environment. AD anonymous LDAP binding is not enabled by
  default. The TechNet article listed in the references section explains how to
  check for anonymous binding (look for 'anonymous binding' in the article:
  anonymous binding is enabled if the seventh bit of the dsHeuristics attribute
  is set to 2)

  Oracle (Sun) JRE is updated to version 1.6.0_37, which addresses multiple
  security issues that existed in earlier releases of Oracle (Sun) JRE.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VMware has updated vCenter Server to address multiple security
  vulnerabilities.");

  script_tag(name:"affected", value:"vCenter Server 5.1 without Update 1
  vCenter Server 5.0 without Update 3.");

  exit(0);
}

include("vmware_esx.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version"))exit(0);
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build"))exit(0);

fixed_builds = make_array("5.0.0","1300600",
                          "5.1.0","1064983");

if ( ! fixed_builds[ vcenter_version] ) exit( 0 );

if ( int( vcenter_build ) < int( fixed_builds[ vcenter_version ] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build: fixed_builds[vcenter_version], typ:'vCenter' ) );
  exit(0);
}

exit(99);