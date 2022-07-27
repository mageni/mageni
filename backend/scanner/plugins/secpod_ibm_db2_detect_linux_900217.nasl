##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_detect_linux_900217.nasl 11885 2018-10-12 13:47:20Z cfischer $
# Description: IBM DB2 Server Detection (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900217");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Product detection");
  script_name("IBM DB2 Server Detection (Linux)");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the version of IBM DB2 Server and saves the
 results in KB.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "IBM DB2 Server Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(sock)
{
        db2Ver = ssh_cmd(socket:sock, cmd:"db2ls -a", timeout:120);
	ssh_close_connection();
        if(!db2Ver){
		exit(0);
	}

	ibmdbVer = eregmatch(pattern:" [.0-9]+", string:strstr(db2Ver, '/'));
	if(ibmdbVer != NULL)
	{
                tmp_version = ibmdbVer[0]- " ";
		set_kb_item(name:"Linux/IBM_db2/Ver", value:tmp_version);
                log_message(data:"IBM DB2 Server version " + ibmdbVer[0] +
                                                  " was detected on the host");

                cpe = build_cpe(value:tmp_version, exp:"^([0-9]\.[0-9])", base:"cpe:/a:ibm:db2:");
                if(!isnull(cpe))
                   register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

		patchVer = eregmatch(pattern:" [.0-9a-z ]+",
				     string:strstr(db2Ver, '/'));

                patchVersion = ereg_replace(pattern:" +[.0-9]+ +([0-9a-z]+).*",
                                            replace:"\1", string:patchVer[0]);
		if(patchVersion != NULL){
			set_kb_item(name:"Linux/IBM_db2/FixPack", value:patchVersion);
                        log_message(data:"IBM DB2 Server FixPack " +
                                   patchVersion + " was detected on the host");
		}
	}
 }
