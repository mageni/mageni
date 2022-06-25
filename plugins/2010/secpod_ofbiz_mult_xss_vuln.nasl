###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ofbiz_mult_xss_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache OFBiz Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:apache:open_for_business_project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901105");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-0432");
  script_bugtraq_id(39489);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Apache OFBiz Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("remote-detect-ApacheOfbiz.nasl");
  script_family("Web application abuses");
  script_mandatory_keys("ApacheOFBiz/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/Apr/139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510746");
  script_xref(name:"URL", value:"http://www.bonsai-sec.com/en/research/vulnerabilities/apacheofbiz-multiple-xss-0103.php");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary HTML and script code
  in the context of an affected site and attackers can steal cookie-based authentication credentials.");

  script_tag(name:"affected", value:"Apache OFBiz 9.04 SVN Revision 920371 and prior");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via,

  (1) the productStoreId parameter to control/exportProductListing,

  (2) the partyId parameter to partymgr/control/viewprofile,

  (3) the start parameter to myportal/control/showPortalPage,

  (4) an invalid URI beginning with /facility/control/ReceiveReturn,

  (5) the contentId parameter to ecommerce/control/ViewBlogArticle,

  (6) the entityName parameter to webtools/control/FindGeneric, or the

  (7) subject or (8) content parameter to an unspecified component under
  ecommerce/control/contactus.");

  script_tag(name:"solution", value:"Upgrade to the latest version of Apache OFBiz.");

  script_tag(name:"summary", value:"This host is running Apache OFBiz and is prone to multiple
  Cross-Site Scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://ofbiz.apache.org/download.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = "/facility/control/ReceiveReturn%22%3Cb%3E%3Cbody%20" +
      "onLoad=%22alert(document.cookie)%22%3E%3Cbr%3E%3Cdi" +
      "v%3E%3E%3C!--";

if( http_vuln_check( port:port, url:url, pattern:"alert\(document.cookie\)", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
