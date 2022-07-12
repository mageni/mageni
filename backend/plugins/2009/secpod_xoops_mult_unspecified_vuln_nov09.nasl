###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xoops_mult_unspecified_vuln_nov09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# XOOPS Multiple Unspecified Vulnerabilities - Nov09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900893");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3963");
  script_bugtraq_id(36955);
  script_name("XOOPS Multiple Unspecified Vulnerabilities - Nov09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54181");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3174");
  script_xref(name:"URL", value:"http://www.xoops.org/modules/news/article.php?storyid=5064");

  script_tag(name:"impact", value:"Unknown impact.");

  script_tag(name:"affected", value:"XOOPS version prior to 2.4.0 Final on all running platform.");

  script_tag(name:"insight", value:"The flaws are caused by unspecified errors with unknown impacts and unknown
  attack vectors.");

  script_tag(name:"solution", value:"Upgrade to XOOPS version 2.4.0 Final or later.");

  script_tag(name:"summary", value:"This host is running XOOPS and is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );