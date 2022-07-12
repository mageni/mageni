###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_62858.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Cisco NX-OS Border Gateway Protocol Component Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

include("revisions-lib.inc");
CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103815");
  script_bugtraq_id(62858);
  script_cve_id("CVE-2012-4098");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11865 $");

  script_name("Cisco NX-OS Border Gateway Protocol Component Denial of Service Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62858");
  script_xref(name:"URL", value:"http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtn13055");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-18 10:24:45 +0200 (Fri, 18 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the BGP service to reset
and resync, denying service to legitimate users.");
  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"This issue is being tracked by Cisco bug ID CSCtn13055.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco NX-OS is prone to a denial-of-service vulnerability because it
fails to properly sanitize user-supplied input.");
  script_tag(name:"affected", value:"Cisco Nexus 7000 Series running on NX-OS.");

  exit(0);
}

include("host_details.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if(!nx_model = get_kb_item("cisco_nx_os/model"))exit(0);
if(!nx_ver = get_kb_item("cisco_nx_os/version"))exit(0);

if( nx_model !~ "^7" ) exit(0);

first_found = '5.2.0.180.S14';
fixed       = '5.2.0.218.S0';

vers = ereg_replace(pattern:'[()]', replace:".", string:nx_ver);

if (revcomp(a:vers, b:first_found) >= 0) {
  security_message(port:0, data:'Installed Version: ' + nx_ver + '\nFixed Version:     5.2(0.218)S0');
  exit(0);

}

exit(99);
