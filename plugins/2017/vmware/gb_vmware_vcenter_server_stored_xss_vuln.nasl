###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vcenter_server_stored_xss_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# VMware vCenter Server H5 Client Stored XSS Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811838");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-4926");
  script_bugtraq_id(100844);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-22 12:05:44 +0530 (Fri, 22 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("VMware vCenter Server H5 Client Stored XSS Vulnerability");

  script_tag(name:"summary", value:"The host is installed with VMware vCenter Server
  and is prone to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input
  handling in vCenter Server H5 Client.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker with VC user privileges to inject malicious java-scripts which will
  get executed when other VC users access the page.");

  script_tag(name:"affected", value:"VMware vCenter Server 6.5 prior to 6.5 U1.");

  script_tag(name:"solution", value:"Upgrade to VMware vCenter Server 6.5 U1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");
  script_xref(name:"URL", value:"http://www.vmware.com");
  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

## http://www.virten.net/vmware/vcenter-release-and-build-number-history
if( vcenter_version =~ "^(6\.5)" && int( vcenter_build ) < int( 5973321 ))
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:"6.5 U1", typ:'vCenter' ) );
  exit(0);
}
