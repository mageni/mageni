###############################################################################
# OpenVAS Vulnerability Test
# $Id: znc_35757.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# ZNC File Upload Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:znc:znc';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100244");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_cve_id("CVE-2009-2658");
  script_bugtraq_id(35757);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ZNC File Upload Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("znc_detect.nasl");
  script_mandatory_keys("znc/version");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35757");
  script_xref(name:"URL", value:"http://znc.svn.sourceforge.net/viewvc/znc?view=rev&sortby=rev&sortdir=down&revision=1570");
  script_xref(name:"URL", value:"http://en.znc.in/wiki/ZNC");

  script_tag(name:"summary", value:"ZNC is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an authenticated attacker to upload
  and overwrite files on the affected computer. Successful exploits will lead to other attacks.");

  script_tag(name:"affected", value:"Versions prior to ZNC 0.072 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"0.072" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.072" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );