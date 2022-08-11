###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_xstatus_dos_vuln_win.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# Pidgin 'X-Status' Message Denial of Service Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901137");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41881);
  script_cve_id("CVE-2010-2528");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Pidgin 'X-Status' Message Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40699");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60566");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1887");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/index.php?id=47");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users.");
  script_tag(name:"affected", value:"Pidgin versions prior to 2.7.2");
  script_tag(name:"insight", value:"The flaw is caused by a NULL pointer dereference error when processing
  malformed 'X-Status' messages, which could be exploited by attackers to
  crash an affected application, creating a denial of service condition.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.7.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Pidgin and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://pidgin.im/download/windows/");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.7.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

