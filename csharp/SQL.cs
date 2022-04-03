using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Collections;

namespace SQL
{
    public class SQL
    {
        static String Run(SqlConnection con, string execCmd)
        {
            SqlCommand command = new SqlCommand(execCmd, con);
            SqlDataReader reader = command.ExecuteReader();
            String res = "";
            while (reader.Read())
            {
                res += reader[0] + "\n";
            }
            reader.Close();
            return res;
        }

        public static void Main(string[] args)
        {
            String sqlServer = args[0];
            String database = "master";
            String command = (args.Length > 1? args[1]: "");

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            using (SqlConnection con = new SqlConnection(conString))
            {
                try
                {
                    con.Open();
                    Console.WriteLine("Auth success!");
                }
                catch
                {
                    Console.WriteLine("Auth failed");
                    return;
                }
                String user = Run(con, "select SYSTEM_USER").Trim();
                String login = Run(con, "select USER_NAME()").Trim();
                Console.WriteLine(String.Format("User: {0}  Login: {1}", user, login));

                foreach (String sql in command.Split('\n'))
                {
                    if(sql.Trim().Length > 0)
                    {
                        Console.WriteLine(Run(con, sql));
                    }
                }
            }
        }
    }
}
