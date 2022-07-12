###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ctorrent_bof_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# CTorrent/Enhanced CTorrent Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900557");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1759");
  script_bugtraq_id(34584);
  script_name("CTorrent/Enhanced CTorrent Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34752");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8470");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49959");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ctorrent_detect.nasl");
  script_mandatory_keys("CTorrent/CTorrent_or_Enhanced/Installed");
  script_tag(name:"impact", value:"Attackers can exploit this issue by execute arbitrary code via
specially crafted torrent files and can cause denial of service.");
  script_tag(name:"affected", value:"CTorrent version 1.3.4 on Linux.
Enhanced CTorrent version 3.3.2 and prior on Linux.");
  script_tag(name:"insight", value:"A stack based buffer overflow is due to a boundary error within
the function 'btFiles::BuildFromMI()' in btfiles.cpp while processing torrent
files containing a long path.");
  script_tag(name:"solution", value:"Apply the appropriate patch.");
  script_tag(name:"summary", value:"The host is installed with CTorrent/Enhanced CTorrent and is
prone to a Buffer Overflow Vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://sourceforge.net/p/dtorrent/bugs/14/");
  script_xref(name:"URL", value:"http://sourceforge.net/p/dtorrent/code/HEAD/tree");
  exit(0);
}


include("version_func.inc");

ctorrentVer = get_kb_item("CTorrent/Ver");
if(ctorrentVer != NULL)
{
  if(version_is_equal(version:ctorrentVer, test_version:"1.3.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

ectorrentVer = get_kb_item("Enhanced/CTorrent/Ver");
if(ectorrentVer != NULL)
{
  if(version_is_less_equal(version:ectorrentVer, test_version:"3.3.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
