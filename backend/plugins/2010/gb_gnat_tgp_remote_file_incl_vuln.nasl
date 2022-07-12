###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnat_tgp_remote_file_incl_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Gnat-TGP 'DOCUMENT_ROOT' Parameter Remote File Include Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800758");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1272");
  script_bugtraq_id(38522);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gnat-TGP 'DOCUMENT_ROOT' Parameter Remote File Include Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56675");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11621");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"Gnat-TGP version 1.2.20 and prior");
  script_tag(name:"insight", value:"The flaw is due to the error in the 'DOCUMENT_ROOT' parameter,
  which allows remote attackers to send a specially-crafted URL request to the 'tgpinc.php' script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Gnat-TGP and is prone remote file include
  vulnerability");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

gnatPort = get_http_port(default:80);

if(!can_host_php(port:gnatPort)){
  exit(0);
}

foreach dir (make_list_unique("/gnat-tgp", "/Gnat-TGP", "/", cgi_dirs(port:gnatPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/gnat/admin/index.php", port:gnatPort);
  rcvRes = http_keepalive_send_recv(port:gnatPort, data:sndReq);

  if("Gnat-TGP" >< rcvRes && rcvRes =~ "HTTP/1.. 200")
  {
    gnatVer = eregmatch(pattern:";([0-9.]+)" , string:rcvRes);
    if(gnatVer[1] != NULL)
    {
      if(version_is_less_equal(version:gnatVer[1], test_version:"1.2.20"))
      {
        security_message(port:gnatPort);
        exit(0);
      }
    }
  }
}

exit(99);