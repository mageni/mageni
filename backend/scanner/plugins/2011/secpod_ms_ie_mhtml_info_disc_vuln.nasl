###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_mhtml_info_disc_vuln.nasl 12490 2018-11-22 13:45:33Z cfischer $
#
# Microsoft Internet Explorer Information Disclosure Vulnerability (2501696)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902285");
  script_version("$Revision: 12490 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:45:33 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-0096");
  script_bugtraq_id(46055);
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (2501696)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2501696");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2501696.mspx");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/46055.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof content,
  disclose information or take any action that the user could take on the
  affected Web site on behalf of the targeted user.");

  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x and 8.x");

  script_tag(name:"insight", value:"The vulnerability exists due to the way MHTML interprets MIME-formatted
  requests for content blocks within a document, which allows an attacker to
  inject a client-side script in the response of a Web request run in the
  context of the victim's Internet Explorer.");

  script_tag(name:"summary", value:"The host is installed with Internet Explorer and is prone to information
  disclosure vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902409.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-026.nasl.