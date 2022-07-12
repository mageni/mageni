##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibmhttpserver_mod_proxy_dos_900222.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: IBM HTTP Server mod_proxy Interim Responses DoS Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900222");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_bugtraq_id(29653);
  script_cve_id("CVE-2008-2364");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("IBM HTTP Server mod_proxy Interim Responses DoS Vulnerability");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8880, 8008);
  script_mandatory_keys("IBM_HTTP_Server/banner");

  script_xref(name:"URL", value:"http://secunia.com/Advisories/31904/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/42987");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=177&context=SSEQTJ&uid=swg21173021");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27008517");

  script_tag(name:"summary", value:"This host is running IBM HTTP Server, which is prone to Denial of
  Service Vulnerability.");

  script_tag(name:"insight", value:"Issue is due to an error in the ap_proxy_http_process_response()
  function in mod_proxy_http.c in the mod_proxy module when processing large number of interim responses
  to the client, which could consume all available memory resources.");

  script_tag(name:"affected", value:"IBM HTTP Server versions prior to 6.1.0.19.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to Fix Pack 19.");
  script_tag(name:"impact", value:"A remote/local user can cause denial of service.");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

ibmWebSer = get_http_banner(port:port);
if(ibmWebSer && egrep(pattern:"Server: IBM_HTTP_Server.*", string:ibmWebSer)) {
  if(egrep(pattern:"IBM_HTTP_Server/([0-5]\..*|6\.[01])[^.0-9]", string:ibmWebSer)) {
    security_message(port);
    exit(0);
  }
}
