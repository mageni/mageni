###############################################################################
# OpenVAS Vulnerability Test
# $Id: yahoo_installed.nasl 12511 2018-11-23 12:41:39Z cfischer $
#
# Yahoo!Messenger is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11432");
  script_version("$Revision: 12511 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 13:41:39 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(2299, 4162, 4163, 4164, 4173, 4837, 4838, 5579, 6121);
  script_cve_id("CVE-2002-0320", "CVE-2002-0321", "CVE-2002-0031", "CVE-2002-0032", "CVE-2002-0322");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Yahoo!Messenger is installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Uninstall this software.");

  script_tag(name:"summary", value:"Yahoo!Messenger - an instant messaging software, which may not be suitable
  for a business environment - is installed on the remote host. If its use
  is not compatible with your corporate policy, you should de-install it.

  This VT has been replaced by 'Yahoo! Messenger Version Detection' (OID: 1.3.6.1.4.1.25623.1.0.801149).");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);