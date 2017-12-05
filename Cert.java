public class Cert{

    private byte[] der;
    private String CN;

    public Cert(byte[] der, String CN) {
        this.der = der;
        this.CN = CN;
    }

    public void setDer(byte[] der) {
        this.der = der;
    }

    public void setCN(String CN){
        this.CN = CN;
    }

    public String getCN(){
        return CN;
    }

    public byte[] getDer() {
        return der;
    }

}
