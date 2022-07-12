###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_ssl_spoof_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Firefox SSL Server Spoofing Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800915");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2408", "CVE-2009-2409");
  script_bugtraq_id(35888);
  script_name("Firefox SSL Server Spoofing Vulnerability (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=510251");
  script_xref(name:"URL", value:"http://www.wired.com/threatlevel/2009/07/kaminsky/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Attackers can exploit this issue via specially crafted certificates
  to spoof arbitrary SSL servers.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 3.5
  NSS versions prior to 3.12.3 on Windows.");

  script_tag(name:"insight", value:"- Lack of validation of domain name in a signed X.509 certificate lead
  to an error while processing a '\0' character in a domain name in the
  subject's common Name (CN) field.

  - Lack of validation of the MD2 hash in a signed X.509 certificate can
  be exploited to generate fake intermediate SSL certificate that would
    be accepted as if it was authentic.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.5 or NSS version 3.12.3 or later.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to SSL server spoofing vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(!firefoxVer){
  exit(0);
}

if(version_is_less(version:firefoxVer, test_version:"3.5"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\firefox.exe", item:"Path");
  if(dllPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath +
                                                                "\nss3.dll");
    dllVer = GetVer(share:share, file:file);
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"3.12.3")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
