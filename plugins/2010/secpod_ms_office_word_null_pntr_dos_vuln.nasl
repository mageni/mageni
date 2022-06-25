###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_word_null_pntr_dos_vuln.nasl 12493 2018-11-22 15:17:57Z cfischer $
#
# Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 secpod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902250");
  script_version("$Revision: 12493 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 16:17:57 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3200");
  script_name("Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/Sep/100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513679/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Word/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service (NULL pointer dereference and multiple-instance application crash).");

  script_tag(name:"affected", value:"Microsoft Office Word 2003 SP3 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'MSO.dll' library which fails to handle
  the special crafted buffer in a file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Microsoft Word and is prone to
  null pointer dereference vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^11\.")
{
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  if(version_in_range(version:wordVer, test_version:"11", test_version2:"11.8326.11.8324"))
  {
    offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
    if(offPath)
    {
      offPath += "\Microsoft Shared\OFFICE11\MSO.DLL";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:offPath);
      file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:offPath);

      dllVer = GetVer(file:file, share:share);
      if(dllVer){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
