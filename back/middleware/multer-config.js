const multer = require("multer");

//Definition of the image formats used.
const MIME_TYPES = {
    "image/jpg": "jpg",
    "image/jpeg": "jpg",
    "image/png": "png"
};

//Indication to Multer where to save the image.
const storage = multer.diskStorage({
    //Send the image to the images folder.
    destination: (req, file, callback) => {
        callback(null, "images")
    },
    //Rename the image file.
    filename: (req, file, callback) => {
        const regex = /[ -]/g;
        const originalNameArray = file.originalname.split(".", 1);
        const originalNameWithoutExt = originalNameArray[0];
        const name = originalNameWithoutExt.split(regex).join("_");
        const extension = MIME_TYPES[file.mimetype];
        callback(null, name + Date.now() + "." + extension);
    }
});

//Check the extension of the image.
function fileFilter (req, file, callback) {
    if (file.mimetype == "image/png" || file.mimetype == "image/jpeg" || file.mimetype == "image/jpg") {
        callback(null, true);  
    } else {
        callback(new Error("Mimetype not accepted."), false);
    }
};

module.exports = multer({ fileFilter, storage }).single("image");