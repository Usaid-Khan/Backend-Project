import { v2 as cloudinary } from "cloudinary"
import fs from "fs"

// Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Upload a Resource
const uploadOnCloudinary = async (localFilePath) => {
    try {
        if(!localFilePath) return null

        // Uploading the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        //console.log("File is uploaded on cloudinary successfully ", response.url)
        
        fs.unlinkSync(localFilePath)
        
        return response
    } catch (error) {
        fs.unlinkSync(localFilePath)    // Remove the locally saved temporary file as upload operation got failed.
        return null
    }
}

export {uploadOnCloudinary}