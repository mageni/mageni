###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_sun_mc_info_disc_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle Sun Management Center Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801587");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2010-4436");
  script_bugtraq_id(45885);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle Sun Management Center Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42989");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64814");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0156");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors.");
  script_tag(name:"affected", value:"Oracle SunMC version 4.0");
  script_tag(name:"insight", value:"The issue is caused by an unknown error within the Web Console component,
  which could allow attackers to disclose certain information.");
  script_tag(name:"summary", value:"The host is installed with Oracle Sun Management Center and is
  prone to information disclosure vulnerability.");
  script_tag(name:"solution", value:"Apply the security updates.

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sun Management Center\";

## if key does not exist, exit
if(!registry_key_exists(key:key)){
  exit(0);
}

smcName = registry_get_sz(key:key, item:"DisplayName");

if("Sun Management Center" >< smcName)
{
  smcVer = registry_get_sz(key:key, item:"BaseProductDirectory");

  if(smcVer == "SunMC4.0"){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
