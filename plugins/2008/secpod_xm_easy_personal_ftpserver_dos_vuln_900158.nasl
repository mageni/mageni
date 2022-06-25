##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xm_easy_personal_ftpserver_dos_vuln_900158.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: XM Easy Personal FTP Server 'NSLT' Command Remote DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900158");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-10-21 15:08:20 +0200 (Tue, 21 Oct 2008)");
  script_cve_id("CVE-2008-5626");
  script_bugtraq_id(31739);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("XM Easy Personal FTP Server 'NSLT' Command Remote DoS Vulnerability");

  script_xref(name:"URL", value:"http://www.dxm2008.com/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6741");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/xm_easy_personal/detected");

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service to legitimate users.");

  script_tag(name:"affected", value:"dxmsoft XM Easy Personal FTP Server version 5.6.0 and prior on Windows (all)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running XM Easy Personal FTP Server, which is prone to
  denial of service vulnerability.

  The vulnerability is due to an error when handling a malformed NLST command.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if(!banner || "DXM's FTP Server" >!< banner)
  exit(0);

if(egrep(pattern:"DXM's FTP Server 5\.([0-5](\..*)?|6\.0)($|[^.0-9])", string:banner)) {
  security_message(port);
  exit(0);
}