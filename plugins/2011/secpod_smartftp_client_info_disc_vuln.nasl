###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartftp_client_info_disc_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# SmartFTP Client Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902448");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SmartFTP Client Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102432/smartftp-disclose.rb.txt");
  script_xref(name:"URL", value:"http://cosine-security.blogspot.com/2011/06/windows-cryptography-with-metasploit.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("FTP");
  script_dependencies("secpod_smartftp_client_detect.nasl");
  script_mandatory_keys("SmartFTP/Client/Ver");
  script_tag(name:"insight", value:"The flaw exists due to the SmartFTP client is not properly saving
the passwords, which allows attackers to find saved login credentials.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with SmartFTP Client and is prone to
information disclosure vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the local attacker gain sensitive
information about the victim's mail folders and can view their contents.");
  script_tag(name:"affected", value:"SmartFTP Client version 4.0.1194.0 and prior.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);

}


include("version_func.inc");

sftpVer = get_kb_item("SmartFTP/Client/Ver");
if(sftpVer != NULL)
{
   if(version_is_less_equal(version:sftpVer, test_version:"4.0.1194.0")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
