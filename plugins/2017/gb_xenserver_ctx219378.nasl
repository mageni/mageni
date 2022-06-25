###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx219378.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Citrix XenServer Multiple Security Updates (CTX219378)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.1140113");
  script_cve_id("CVE-2016-9932", "CVE-2016-10024", "CVE-2016-10025");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11982 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX219378)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX219378");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"Security vulnerabilities have been identified in Citrix XenServer that may allow malicious code running within a guest VM to read a small part of hypervisor memory and allow privileged-mode code running within a guest VM to hang or crash the host.

The following vulnerabilities have been addressed:

CVE-2016-9932 (Low): x86 CMPXCHG8B emulation fails to ignore operand size override
CVE-2016-10024 (Medium): x86 PV guests may be able to mask interrupts
CVE-2016-10025 (Low): missing NULL pointer check in VMFUNC emulation");

  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix XenServer 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-03 10:14:13 +0100 (Tue, 03 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("citrix_version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") ) exit( 0 );

patches = make_array();

patches['7.0.0'] = make_list( 'XS70E023' );
patches['6.5.0'] = make_list( 'XS65ESP1046' );
patches['6.2.0'] = make_list( 'XS62ESP1054' );
patches['6.0.2'] = make_list( 'XS602ECC039' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );
