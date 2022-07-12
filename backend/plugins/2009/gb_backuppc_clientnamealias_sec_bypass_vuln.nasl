###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_backuppc_clientnamealias_sec_bypass_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# BackupPC 'ClientNameAlias' Function Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801107");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3369");
  script_name("BackupPC 'ClientNameAlias' Function Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36393");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=542218");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_backuppc_detect.nasl");
  script_mandatory_keys("BackupPC/Ver");
  script_tag(name:"impact", value:"Successful attacks may allow remote authenticated users to read
and write sensitive files by modifying ClientNameAlias to match another system,
then initiating a backup or restore on the victim's system.");
  script_tag(name:"affected", value:"BackupPC version 3.1.0 and prior.");
  script_tag(name:"insight", value:"The security issue is due to the application allowing users to
set the 'ClientNameAlias' option for configured hosts. This can be exploited to
backup arbitrary directories from client systems for which Rsync over SSH is
configured as a transfer method.");
  script_tag(name:"summary", value:"This host has BackupPC intallation and is prone to security
bypass vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Update to version 3.1.0-7 or later.");
  script_xref(name:"URL", value:"http://backuppc.sourceforge.net");
  exit(0);
}


include("version_func.inc");

backuppcVer = get_kb_item("BackupPC/Ver");
if(backuppcVer)
{
  if(version_in_range(version:backuppcVer, test_version:"3.0",
                                           test_version2:"3.1.0")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
