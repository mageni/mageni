###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_klite_mega_codec_dos_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# K-Lite Mega Codec Pack vsfilter.dll Denial Of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800139");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5072");
  script_bugtraq_id(31400);
  script_name("K-Lite Mega Codec Pack vsfilter.dll Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6565");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45446");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"By tricking a user to interact with a specially crafted .flv file,
  attackers can cause Windows Explorer to crash.");
  script_tag(name:"insight", value:"The flaw is due to error in vsfilter.dll file, which fails to properly
  validate the input data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with K-Lite Mega Codec Pack and is prone to
  Denial Of Service Vulnerability.");
  script_tag(name:"affected", value:"K-Lite Mega Codec Pack 3.5.7.0 and earlier on Windows (Any).

  *****
  NOTE : Some Higher Versions of K-Lite Mega Codec Pack seems to be
  also vulnerable.
  *****");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.codecguide.com/download_mega.htm");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

klitePath = registry_get_sz(key:"SOFTWARE\KLCodecPack", item:"installdir");
if(!klitePath){
  exit(0);
}

klitePath += "\Filters\vsfilter.dll";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:klitePath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:klitePath);

kliteVer = GetVer(file:file, share:share);
if(!kliteVer){
  exit(0);
}

if(version_is_less(version:kliteVer, test_version:"1.0.1.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
