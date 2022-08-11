###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_necko_dns_info_disc_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Mozilla Products Necko DNS Information Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800455");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4629");
  script_name("Mozilla Products Necko DNS Information Disclosure Vulnerability (Windows)");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=492196");
  script_xref(name:"URL", value:"https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");
  script_xref(name:"URL", value:"https://bug492196.bugzilla.mozilla.org/attachment.cgi?id=377824");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let the attackers obtain the network location of
  the applications user by logging DNS requests.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version 3.0.1 and
  Seamonkey with Mozilla Necko version 1.9.0 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw exists while DNS prefetching, when the app type is 'APP_TYPE_MAIL'
  or 'APP_TYPE_EDITOR'");
  script_tag(name:"summary", value:"The host is installed with Thundebird/Seamonkey and is prone to
  Information Disclosure vulnerability.");
  script_tag(name:"solution", value:"Apply the referenced patch or Upgrade to  Mozilla Necko version 1.9.1

  NOTE: Ignore this warning, if above mentioned patch is already applied.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");
if(!isnullsmVer)
{

  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\App Paths\seamonkey.exe", item:"path");
  path = path + "\seamonkey.exe";

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:path);

  seaVer = GetVer(file:file, share:share);
  if(!isnull(seaVer))
  {
    if(version_is_less(version:seaVer, test_version:"1.9.1"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

fpVer = get_kb_item("Thunderbird/Win/Ver");
if(!isnull(fpVer))
{
  if(version_is_less_equal(version:fpVer, test_version:"3.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
