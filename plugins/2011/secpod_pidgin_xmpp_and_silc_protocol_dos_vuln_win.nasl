###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_xmpp_and_silc_protocol_dos_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Pidgin XMPP And SILC Protocols Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902650");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4601");
  script_bugtraq_id(51070, 51074);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-21 11:02:55 +0530 (Wed, 21 Dec 2011)");
  script_name("Pidgin XMPP And SILC Protocols Denial of Service Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=57");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=58");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=59");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users.");
  script_tag(name:"affected", value:"Pidgin versions prior to 2.10.1");
  script_tag(name:"insight", value:"Multiplw flaws are due to

  - An error in the silc_channel_message function in ops.c in the SILC
    protocol plugin in libpurple, which fails to validate that a piece of text
    was UTF-8 when receiving various incoming messages.

  - An error in the XMPP protocol plugin in libpurple, which fails to ensure
    that the incoming message contained all required fields when receiving
    various stanzas related to voice and video chat.

  - An error in the family_feedbag.c in the oscar protocol plugin, which fails
    to validate that a piece of text was UTF-8 when receiving various incoming
    messages.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Pidgin and is prone to denial of
  service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://pidgin.im/download/windows/");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
