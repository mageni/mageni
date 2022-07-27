###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nec_aterm_wg2600hp2_incorrect_access_ctrl_vuln.nasl 12998 2019-01-09 13:46:07Z asteins $
#
# NEC Aterm WG2600HP2 Incorrect Access Control Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813880");
  script_version("2019-03-22T15:58:59+0000");
  script_cve_id("CVE-2017-12575");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-22 15:58:59 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-09-07 18:21:50 +0530 (Fri, 07 Sep 2018)");

  script_name("NEC Aterm WG2600HP2 Incorrect Access Control Vulnerability");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Aug/26");
  script_xref(name:"URL", value:"http://www.aterm.jp/product/atermstation/product/warpstar/wg2600hp2");

  script_tag(name:"summary", value:"The host is installed with NEC Aterm WG2600HP2
  wireless LAN router and is prone to an incorrect access control vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks
  whether it is able to access sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exist due to an incorrect access control for some web service APIs.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access configurations. This may aid to launch further attacks.");

  script_tag(name:"affected", value:"NEC Aterm WG2600HP2 wireless LAN router");

  script_tag(name:"solution", value:"No known solution is available as of 22nd March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

necport = get_http_port(default:80);

buf = http_get_cache(item:"/aterm_httpif.cgi", port:necport);

## Application confirmation
## WG2600HP2 is not able to confirm
if(buf =~ "Copyright.*NEC Platforms" && buf =~ "<title>.*Aterm</title>" &&
   "Server: Aterm(HT)" >< buf)
{
  data = "REQ_ID=SUPPORT_IF_GET";
  url = "/aterm_httpif.cgi/negotiate";

  req = http_post_req(port:necport, url:url, data:data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
  buf = http_keepalive_send_recv(port:necport, data:req);

  if(buf =~ "^HTTP/1\.[01] 200" && "DEVICE_TYPE=" >< buf && "SUPPORT_REQ=" >< buf &&
   "Server: Aterm(HT)" >< buf && "GET_INTERFACE=" >< buf && "SET_INTERFACE=" >< buf)
  {
    report = report_vuln_url(port:necport, url:url);
    security_message(port:necport, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
