/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptol2z1;

/**
 *
 * @author Patryk Kozieł
 */
class CPAPair {
    
    byte[] encryptedMsg;
    byte[] IV;

    public CPAPair(byte[] encryptedMsg, byte[] IV) {
        this.encryptedMsg = encryptedMsg;
        this.IV = IV;
    }
    
}
