using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Windows.Forms;

namespace CEncryptor
{
    public partial class CForm : Form
    {
        public CForm()
        {
            InitializeComponent();
        }
      
       

        private void CForm_Load(object sender, EventArgs e)
        {
            bool showP = (sHold.Controls.Cast<Control>().Where(x => x is TextBox).First() as TextBox).PasswordChar == '\u0000';
            btnShow.Text = showP ? "hide values" : "show values";
            this.Text = "CEncryptor/Decryptor " + System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;

            ValidatePassword();
        }
        private bool ValidatePassword()
        {

            lblPasswordValidation.Text = "";
            bool valid = true;
            if (txtp.Text.Trim() == "")
            {
                lblPasswordValidation.Text = "* Password is empty!";
                valid = false;
            }
            else if (txtp.Text != txtp2.Text)
            {
                lblPasswordValidation.Text = "* Passwords does not match!";
                valid = false;
            }
            btnEncrypt.Enabled = valid;
            txtS.Enabled = valid;
            return valid;
        }

        private void btnShow_Click(object sender, EventArgs e)
        {
            var allBoxes = sHold.Controls.Cast<Control>().Where(x => x is TextBox).Select(x=>x as TextBox).ToList();

            bool showP = allBoxes.First().PasswordChar == '\u0000';

            //Ja redzami tad slēpjam
            foreach(var t in allBoxes)
            {
                if (!showP)
                {
                    t.PasswordChar = '\u0000';
                }
                else
                {
                    t.PasswordChar = '*';

                }
            }
            btnShow.Text = showP ? "hide values" : "show values";
        }

        

        private void txtRaw_TextChanged(object sender, EventArgs e)
        {
            string[] lines = txtRaw.Lines;
            List<string> resultLines = new List<string>();
            int counter = 0;
            bool mustReupdateText = false;
            int currentPos = txtRaw.SelectionStart;

            //Šo ciklu tomēr vajadzēja atstāt, lai zinātu, kad jauna rinda bez skaitītāja radusies... 
            foreach (string line in lines)
            {
                string[] splitted = line.Split(' ', ';', ',');
                foreach (string s1 in splitted)
                {
                    string tmp = s1;
                    if (tmp != "")
                    {
                        counter++;
                        if (!tmp.Contains(":"))
                        {
                            tmp = counter + ":" + tmp;
                            mustReupdateText = true;
                            
                            currentPos = currentPos + counter.ToString().Length+1;
                        }

                        resultLines.Add(tmp);
                    }
                }
            }

            if (mustReupdateText)
            {
                List<string> withoutNumbers = resultLines.Where(x => x.Contains(":")).Select(x => x.Split(':')[1]).ToList();

                List<string> withNumbers = new List<string>();
                int cc = 0;
                foreach (string s in withoutNumbers)
                {
                    cc++;
                    withNumbers.Add(cc + ":" + s);

                }
                txtRaw.Text = string.Join("\n", withNumbers.ToArray());

            }


            txtRaw.Select(currentPos, 0);
            txtRaw.ScrollToCaret();

        }

        private void p_TextChanged(object sender, EventArgs e)
        {
            ValidatePassword();
        }
        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            txtRes.Text = "";
            if (tcESource.SelectedTab == tabWords)
            {
                var foundTxtBoxes = sHold.Controls.Cast<Control>().Where(x => x is TextBox).OrderBy(x => x.Name).ToList();
                List<string> valuesSource = foundTxtBoxes.Select(x => x.Text).ToList();
                updateResult(valuesSource);
            }
            else if (tcESource.SelectedTab == tabRawTxt)
            {
                txtRaw_TextChanged(txtRaw, e);
                List<string> withoutNumbers = txtRaw.Lines.Where(x => x.Contains(":")).Select(x => x.Split(':')[1]).ToList();
              
                updateResult(withoutNumbers);
            }
            else
            {
                MessageBox.Show("p:Not supported");
            }
        }
        private void updateResult(List<string> valuesSource)
        {
            //Encodes all words seperatly and joins together and encrypts another time (to hide seperate part count)
            List<string> values = new List<string>();
            int counter = 0;
            foreach (var v in valuesSource)
            {
                counter++;
                string cs = StringCipher.Encrypt(v, txtp.Text + "Inner");
                values.Add(cs);
            }
            string entireS = string.Join("@@", values.ToArray());
            string entireC = StringCipher.Encrypt(entireS, txtp.Text + "Outer");
            txtRes.Text = entireC;
        }
        /// <summary>
        /// Decrypted part collection
        /// </summary>
        List<string> partsLast = new List<string>();
        int counterI = 0;
        private void txtS_TextChanged(object sender, EventArgs e)
        {
            if (txtS.Text != "")
            {
                counterI = 0;
                try
                {
                    string d1 = StringCipher.Decrypt(txtS.Text, txtp.Text + "Outer");
                    partsLast = d1.Split(new string[] { "@@" }, StringSplitOptions.RemoveEmptyEntries).ToList();
                }
                catch
                {
                    //-txtD.Text = "Access denied";
                    MessageBox.Show("Access denied");
                    lblC.Text = "Access denied";
                    txtS.Text = "";
                    return;
                }
                lblC.Text = "Ready (" + partsLast.Count + " )";
                lblx.Text = "...";
                btnL.Enabled = false;
                btnR.Enabled = true;

            }
        }
        private void btnR_Click(object sender, EventArgs e)
        {
            if (counterI <= partsLast.Count)
                counterI++;

            btnR.Enabled = counterI != partsLast.Count;
            btnL.Enabled = counterI != 1;

            string elementAt = partsLast.ElementAt(counterI - 1);
            string dc = "";
            try
            {
                dc = StringCipher.Decrypt(elementAt, txtp.Text + "Inner");
                lblx.Text = dc;
                lblC.Text = counterI + "";
            }
            catch
            {

                throw new Exception("Access denied - not supported action");
            }
        }

        private void btnL_Click(object sender, EventArgs e)
        {
            if (counterI > 1)
                counterI--;
            btnR.Enabled = counterI != partsLast.Count;
            btnL.Enabled = counterI != 1;

            string elementAt = partsLast.ElementAt(counterI - 1);
            
            try
            {
                string dc = StringCipher.Decrypt(elementAt, txtp.Text + "Inner");
                lblx.Text = dc;
                lblC.Text = counterI + "";
            }
            catch
            {
                throw new Exception("Access denied - not supported action");
            }
        }

        private void tcESource_SelectedIndexChanged(object sender, EventArgs e)
        {
            txtRes.Text = "";
        }
    }
}
